module type Monad =
  sig
    type 'a t
    val return : 'a -> 'a t
    val bind : 'a t -> ('a -> 'b t) -> 'b t
  end

module type Monad_ext =
  sig
    type 'a t
    val return : 'a -> 'a t
    val bind : 'a t -> ('a -> 'b t) -> 'b t
    val ( >>= ) : 'a t -> ('a -> 'b t) -> 'b t
    val ( >|= ) : 'a t -> ('a -> 'b) -> 'b t
    val map : ('a -> 'b) -> 'a t -> 'b t
    val sequence : 'a t list -> 'a list t
    val sequence_ : 'a t list -> unit t
    val mapM : ('a -> 'b t) -> 'a list -> 'b list t
    val mapM_ : ('a -> 'b t) -> 'a list -> unit t
    val foldM : ('a -> 'b -> 'a t) -> 'a -> 'b list -> 'a t
  end

module Monad_ext_make :
  functor (M : Monad) ->
    sig
      type 'a t = 'a M.t
      val return : 'a -> 'a t
      val bind : 'a t -> ('a -> 'b t) -> 'b t
      val ( >>= ) : 'a t -> ('a -> 'b t) -> 'b t
      val ( >|= ) : 'a t -> ('a -> 'b) -> 'b t
      val map : ('a -> 'b) -> 'a t -> 'b t
      val sequence : 'a t list -> 'a list t
      val sequence_ : 'a t list -> unit t
      val mapM : ('a -> 'b t) -> 'a list -> 'b list t
      val mapM_ : ('a -> 'b t) -> 'a list -> unit t
      val foldM : ('a -> 'b -> 'a t) -> 'a -> 'b list -> 'a t
    end

module type Or_error =
  sig
    type err
    type 'a t
    val fail : err -> 'a t
    val is_success : 'a t -> bool
    val is_error : 'a t -> bool
    val return : 'a -> 'a t
    val bind : 'a t -> ('a -> 'b t) -> 'b t
    val ( >>= ) : 'a t -> ('a -> 'b t) -> 'b t
    val ( >|= ) : 'a t -> ('a -> 'b) -> 'b t
    val map : ('a -> 'b) -> 'a t -> 'b t
    val sequence : 'a t list -> 'a list t
    val sequence_ : 'a t list -> unit t
    val mapM : ('a -> 'b t) -> 'a list -> 'b list t
    val mapM_ : ('a -> 'b t) -> 'a list -> unit t
    val foldM : ('a -> 'b -> 'a t) -> 'a -> 'b list -> 'a t
    val guard : bool -> err -> unit t
    val or_else : 'a t -> 'a -> 'a
    val or_else_f : 'a t -> ('b -> 'a) -> 'b -> 'a
  end

module Or_error_make :
  functor (M : sig type err end) ->
    sig
      type err = M.err
      type 'a t = ('a, M.err) Result.result
      val fail : err -> 'a t
      val is_success : 'a t -> bool
      val is_error : 'a t -> bool
      val return : 'a -> 'a t
      val bind : 'a t -> ('a -> 'b t) -> 'b t
      val ( >>= ) : 'a t -> ('a -> 'b t) -> 'b t
      val ( >|= ) : 'a t -> ('a -> 'b) -> 'b t
      val map : ('a -> 'b) -> 'a t -> 'b t
      val sequence : 'a t list -> 'a list t
      val sequence_ : 'a t list -> unit t
      val mapM : ('a -> 'b t) -> 'a list -> 'b list t
      val mapM_ : ('a -> 'b t) -> 'a list -> unit t
      val foldM : ('a -> 'b -> 'a t) -> 'a -> 'b list -> 'a t
      val guard : bool -> err -> unit t
      val or_else : 'a t -> 'a -> 'a
      val or_else_f : 'a t -> ('b -> 'a) -> 'b -> 'a
    end
